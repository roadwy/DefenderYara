
rule Trojan_Win32_Zusy_GTN_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 41 00 47 44 49 33 32 2e 64 6c 6c 00 00 00 42 ?? 74 ?? 6c 74 ?? 57 53 32 ?? 33 32 2e 64 6c 6c 00 64 33 ?? 39 2e 64 6c 6c 00 00 00 44 69 ?? 65 63 74 33 ?? 43 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}