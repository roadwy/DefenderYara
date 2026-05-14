
rule Trojan_Win32_RemotExec_PAA_MTB{
	meta:
		description = "Trojan:Win32/RemotExec.PAA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 00 76 00 20 00 2f 00 63 00 } //1 /v /c
		$a_02_1 = {3d 00 25 00 63 00 64 00 25 00 5c 00 [0-3f] 2e 00 6c 00 6e 00 6b 00 } //3
		$a_00_2 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 } //3 \AppData\Local
		$a_00_3 = {26 00 3e 00 6e 00 75 00 6c 00 20 00 63 00 65 00 21 00 66 00 21 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 } //3 &>nul ce!f!tutil -decode
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3) >=10
 
}