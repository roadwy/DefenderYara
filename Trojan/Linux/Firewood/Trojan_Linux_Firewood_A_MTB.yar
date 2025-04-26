
rule Trojan_Linux_Firewood_A_MTB{
	meta:
		description = "Trojan:Linux/Firewood.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 66 20 2d 68 7c 67 72 65 70 20 27 64 65 76 27 20 7c 67 72 65 70 20 2d 76 20 6e 6f 6e 65 7c 61 77 6b 20 27 2f 64 65 76 2f 7b 70 72 69 6e 74 20 24 36 7d 27 } //1 df -h|grep 'dev' |grep -v none|awk '/dev/{print $6}'
		$a_01_1 = {63 61 74 20 2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f 20 7c 20 67 72 65 70 20 22 6d 6f 64 65 6c 20 6e 61 6d 65 22 } //1 cat /proc/cpuinfo | grep "model name"
		$a_01_2 = {6b 69 6c 6c 20 25 64 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c } //1 kill %d 2>/dev/null
		$a_01_3 = {69 6e 73 6d 6f 64 20 2d 66 20 25 73 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c } //1 insmod -f %s 2>/dev/null
		$a_01_4 = {58 2d 47 4e 4f 4d 45 2d 41 75 74 6f 73 74 61 72 74 2d 65 6e 61 62 6c 65 64 3d 74 72 75 65 } //1 X-GNOME-Autostart-enabled=true
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}