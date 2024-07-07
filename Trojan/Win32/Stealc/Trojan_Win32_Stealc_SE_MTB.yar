
rule Trojan_Win32_Stealc_SE_MTB{
	meta:
		description = "Trojan:Win32/Stealc.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 81 c3 3c 11 00 00 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 af } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}