
rule Trojan_Win32_SystemBC_psyH_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 00 00 59 8b c7 5f 5e 5b 8b e5 5d c3 33 c0 50 50 50 50 50 e8 0a 17 00 00 cc 8b ff 55 8b ec 56 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}