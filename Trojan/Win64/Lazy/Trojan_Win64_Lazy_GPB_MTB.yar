
rule Trojan_Win64_Lazy_GPB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 69 76 61 6a 69 20 43 6f 6d 73 5c 42 69 76 61 41 70 70 } //1 Software\Bivaji Coms\BivaApp
	condition:
		((#a_01_0  & 1)*1) >=1
 
}