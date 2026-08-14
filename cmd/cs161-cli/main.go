package main

// CS161 Project 2 - CLI 命令行入口
// 业务域：基础服务域（Agent 接入层）
// 借鉴学城 Citadel Skill 的 CLI 设计：通过 cobra 命令行包装 client 包核心函数，
// 让 AI Agent 可以通过 CLI + REST API 调用文件系统

import (
	"fmt"
	"os"

	"github.com/cs161-staff/project2-starter-code/client"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// newRootCmd 构造 cobra root command，挂载所有子命令
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cs161",
		Short: "CS161 加密文件系统 CLI",
		Long:  "CS161 安全文件系统命令行工具，支持用户/文件/共享操作",
	}
	root.AddCommand(newUserCmd(), newFileCmd(), newShareCmd())
	return root
}

// user 子命令组：user init / user get
func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "用户管理",
	}
	cmd.AddCommand(newUserInitCmd())
	return cmd
}

func newUserInitCmd() *cobra.Command {
	var username, password string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "创建新用户",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.InitUser(username, password)
			if err != nil {
				return fmt.Errorf("user init failed: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "user %s initialized successfully\n", username)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "用户名（必填）")
	cmd.Flags().StringVar(&password, "password", "", "密码（必填）")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	return cmd
}

// file 子命令组：file store / file load / file append
func newFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "file",
		Short: "文件操作",
	}
	cmd.AddCommand(newFileStoreCmd(), newFileLoadCmd(), newFileAppendCmd())
	return cmd
}

func newFileStoreCmd() *cobra.Command {
	var username, password, filename, data string
	cmd := &cobra.Command{
		Use:   "store",
		Short: "存储文件",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := client.GetUser(username, password)
			if err != nil {
				return fmt.Errorf("get user failed: %v", err)
			}
			if err := u.StoreFile(filename, []byte(data)); err != nil {
				return fmt.Errorf("store file failed: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored %d bytes to %s\n", len(data), filename)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "用户名")
	cmd.Flags().StringVar(&password, "password", "", "密码")
	cmd.Flags().StringVar(&filename, "filename", "", "文件名")
	cmd.Flags().StringVar(&data, "data", "", "要存储的数据")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("filename")
	cmd.MarkFlagRequired("data")
	return cmd
}

func newFileLoadCmd() *cobra.Command {
	var username, password, filename string
	cmd := &cobra.Command{
		Use:   "load",
		Short: "加载文件",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := client.GetUser(username, password)
			if err != nil {
				return fmt.Errorf("get user failed: %v", err)
			}
			data, err := u.LoadFile(filename)
			if err != nil {
				return fmt.Errorf("load file failed: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", string(data))
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "用户名")
	cmd.Flags().StringVar(&password, "password", "", "密码")
	cmd.Flags().StringVar(&filename, "filename", "", "文件名")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("filename")
	return cmd
}

func newFileAppendCmd() *cobra.Command {
	var username, password, filename, data string
	cmd := &cobra.Command{
		Use:   "append",
		Short: "追加数据到文件",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := client.GetUser(username, password)
			if err != nil {
				return fmt.Errorf("get user failed: %v", err)
			}
			if err := u.AppendWithRetry(filename, []byte(data), 3); err != nil {
				return fmt.Errorf("append file failed: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "appended %d bytes to %s\n", len(data), filename)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "用户名")
	cmd.Flags().StringVar(&password, "password", "", "密码")
	cmd.Flags().StringVar(&filename, "filename", "", "文件名")
	cmd.Flags().StringVar(&data, "data", "", "追加数据")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("filename")
	cmd.MarkFlagRequired("data")
	return cmd
}

// share 子命令组：share invite / share accept / share revoke
func newShareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "share",
		Short: "共享操作",
	}
	cmd.AddCommand(newShareInviteCmd(), newShareAcceptCmd(), newShareRevokeCmd())
	return cmd
}

func newShareInviteCmd() *cobra.Command {
	var username, password, filename, recipient string
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "创建共享邀请",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := client.GetUser(username, password)
			if err != nil {
				return fmt.Errorf("get user failed: %v", err)
			}
			invID, err := u.CreateInvitation(filename, recipient)
			if err != nil {
				return fmt.Errorf("create invitation failed: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "invitation id: %s\n", invID.String())
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "发送者用户名")
	cmd.Flags().StringVar(&password, "password", "", "发送者密码")
	cmd.Flags().StringVar(&filename, "filename", "", "要共享的文件名")
	cmd.Flags().StringVar(&recipient, "recipient", "", "接收者用户名")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("filename")
	cmd.MarkFlagRequired("recipient")
	return cmd
}

func newShareAcceptCmd() *cobra.Command {
	var username, password, sender, filename, invitationID string
	cmd := &cobra.Command{
		Use:   "accept",
		Short: "接受共享邀请",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := client.GetUser(username, password)
			if err != nil {
				return fmt.Errorf("get user failed: %v", err)
			}
			invUUID, err := uuid.Parse(invitationID)
			if err != nil {
				return fmt.Errorf("invalid invitation id: %v", err)
			}
			if err := u.AcceptInvitation(sender, invUUID, filename); err != nil {
				return fmt.Errorf("accept invitation failed: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "accepted invitation, filename=%s\n", filename)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "接收者用户名")
	cmd.Flags().StringVar(&password, "password", "", "接收者密码")
	cmd.Flags().StringVar(&sender, "sender", "", "发送者用户名")
	cmd.Flags().StringVar(&filename, "filename", "", "保存为的文件名")
	cmd.Flags().StringVar(&invitationID, "invitation-id", "", "invitation UUID（hex）")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("sender")
	cmd.MarkFlagRequired("filename")
	cmd.MarkFlagRequired("invitation-id")
	return cmd
}

func newShareRevokeCmd() *cobra.Command {
	var username, password, filename, recipient string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "撤销共享",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := client.GetUser(username, password)
			if err != nil {
				return fmt.Errorf("get user failed: %v", err)
			}
			if err := u.RevokeAccess(filename, recipient); err != nil {
				return fmt.Errorf("revoke access failed: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked %s access to %s\n", recipient, filename)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "所有者用户名")
	cmd.Flags().StringVar(&password, "password", "", "所有者密码")
	cmd.Flags().StringVar(&filename, "filename", "", "文件名")
	cmd.Flags().StringVar(&recipient, "recipient", "", "被撤销者用户名")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")
	cmd.MarkFlagRequired("filename")
	cmd.MarkFlagRequired("recipient")
	return cmd
}

// uuidFromBytes 工具函数（保留以备后用）
// func uuidFromBytes(b []byte) (uuid.UUID, error) {
// 	return uuid.FromBytes(b)
// }

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
