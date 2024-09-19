
rule Trojan_Win32_Rozena_YAD_MTB{
	meta:
		description = "Trojan:Win32/Rozena.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e6 8b cd c1 ea 03 6b c2 19 2b c8 03 ce 8a 44 0c 20 32 86 00 70 50 00 46 88 47 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}