
rule Trojan_Win32_Farfli_BP_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 ea 76 80 f2 23 88 14 01 41 3b ce 7c } //00 00 
	condition:
		any of ($a_*)
 
}