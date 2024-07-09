
rule Trojan_Linux_HidWasp_A_MTB{
	meta:
		description = "Trojan:Linux/HidWasp.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 72 6f 6a 61 6e 2d 48 6f 73 74 6e 61 6d 65 } //1 Trojan-Hostname
		$a_02_1 = {78 78 64 20 2d 72 20 2d 70 20 3e 20 25 73 2e 74 6d 70 [0-02] 63 68 6d 6f 64 20 2d 2d 72 65 66 65 72 65 6e 63 65 20 25 73 20 25 73 2e 74 6d 70 [0-02] 6d 76 20 25 73 2e 74 6d 70 } //1
		$a_00_2 = {49 5f 41 4d 5f 48 49 44 44 45 4e } //1 I_AM_HIDDEN
		$a_00_3 = {74 6d 70 2e 73 63 70 2e 58 58 58 58 58 58 } //1 tmp.scp.XXXXXX
		$a_00_4 = {48 49 44 45 5f 54 48 49 53 5f 53 48 45 4c 4c } //1 HIDE_THIS_SHELL
		$a_00_5 = {66 61 6b 65 5f 70 72 6f 63 65 73 73 6e 61 6d 65 } //1 fake_processname
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}