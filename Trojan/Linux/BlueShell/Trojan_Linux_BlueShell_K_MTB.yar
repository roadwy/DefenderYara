
rule Trojan_Linux_BlueShell_K_MTB{
	meta:
		description = "Trojan:Linux/BlueShell.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,15 00 15 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 49 43 45 43 61 63 68 65 } //10 /tmp/.ICECache
		$a_00_1 = {2f 74 6d 70 2f 6b 74 68 72 65 61 64 } //10 /tmp/kthread
		$a_00_2 = {6c 67 64 74 3d } //10 lgdt=
		$a_00_3 = {2f 75 73 72 2f 6c 69 62 2f 73 79 73 74 65 6d 64 2f 73 79 73 74 65 6d 64 2d 75 64 65 76 64 } //1 /usr/lib/systemd/systemd-udevd
		$a_00_4 = {2f 75 73 72 2f 6c 69 62 65 78 65 63 2f 72 70 63 69 6f 64 } //1 /usr/libexec/rpciod
		$a_00_5 = {2f 75 73 72 2f 73 62 69 6e 2f 63 72 6f 6e 20 2d 66 } //1 /usr/sbin/cron -f
		$a_00_6 = {2f 73 62 69 6e 2f 72 70 63 64 } //1 /sbin/rpcd
		$a_00_7 = {2f 68 6f 6d 65 2f 55 73 65 72 2f 44 65 73 6b 74 6f 70 2f 63 6c 69 65 6e 74 2f 6d 61 69 6e 2e 67 6f } //1 /home/User/Desktop/client/main.go
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=21
 
}