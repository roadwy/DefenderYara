
rule Trojan_Win32_StealC_AMZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 75 f8 89 75 d0 8b 45 d0 29 45 f4 81 45 ec 47 86 c8 61 ff 4d e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}