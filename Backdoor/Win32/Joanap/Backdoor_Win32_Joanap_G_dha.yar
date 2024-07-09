
rule Backdoor_Win32_Joanap_G_dha{
	meta:
		description = "Backdoor:Win32/Joanap.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {52 70 63 73 73 00 [0-0a] 25 73 5c 25 73 [0-0a] 77 61 75 73 65 72 76 2e 64 6c 6c 00 64 2e 62 61 74 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}