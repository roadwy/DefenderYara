
rule Backdoor_Linux_Dofloo_A_xp{
	meta:
		description = "Backdoor:Linux/Dofloo.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {48 61 63 6b 65 72 } //1 Hacker
		$a_00_1 = {56 45 52 53 4f 4e 45 58 3a 4c 69 6e 75 78 2d 25 73 7c 25 64 7c 25 64 20 4d 48 7a 7c 25 64 4d 42 7c 25 64 4d 42 7c 25 73 } //1 VERSONEX:Linux-%s|%d|%d MHz|%dMB|%dMB|%s
		$a_00_2 = {73 65 64 20 2d 69 20 2d 65 20 27 2f 25 73 2f 64 27 20 2f 65 74 63 2f 72 63 2e 6c 6f 63 61 6c } //1 sed -i -e '/%s/d' /etc/rc.local
		$a_00_3 = {73 65 64 20 2d 69 20 2d 65 20 27 32 20 69 25 73 2f 25 73 27 20 2f 65 74 63 2f 72 63 2e 6c 6f 63 61 6c } //1 sed -i -e '2 i%s/%s' /etc/rc.local
		$a_00_4 = {73 65 64 20 2d 69 20 2d 65 20 27 32 20 69 25 73 2f 25 73 20 73 74 61 72 74 27 20 2f 65 74 63 2f 72 63 2e 64 2f 72 63 2e 6c 6f 63 61 6c } //1 sed -i -e '2 i%s/%s start' /etc/rc.d/rc.local
		$a_00_5 = {73 65 64 20 2d 69 20 2d 65 20 27 32 20 69 25 73 2f 25 73 20 73 74 61 72 74 27 20 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 62 6f 6f 74 2e 6c 6f 63 61 6c } //1 sed -i -e '2 i%s/%s start' /etc/init.d/boot.local
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}