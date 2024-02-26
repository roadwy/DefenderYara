
rule Trojan_Win32_StealC_NA_MTB{
	meta:
		description = "Trojan:Win32/StealC.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {59 5f 5f 5e 5b 8b e5 5d 51 c3 cc cc cc 8b 07 83 f8 fe 74 0d 8b 4f 04 03 ce 33 0c 30 e8 79 d4 ff ff 8b 4f 0c 8b 47 08 03 ce 33 0c 30 e9 } //00 00 
	condition:
		any of ($a_*)
 
}