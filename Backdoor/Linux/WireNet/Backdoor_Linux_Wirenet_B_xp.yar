
rule Backdoor_Linux_Wirenet_B_xp{
	meta:
		description = "Backdoor:Linux/Wirenet.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 6e 63 74 66 2e 74 78 74 } //2 /tmp/nctf.txt
		$a_01_1 = {40 72 65 62 6f 6f 74 } //1 @reboot
		$a_01_2 = {63 72 6f 6e 74 61 62 20 2f 74 6d 70 2f 6e 63 74 66 2e 74 78 74 20 32 3e } //1 crontab /tmp/nctf.txt 2>
		$a_01_3 = {46 69 6e 20 57 61 69 74 } //1 Fin Wait
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}