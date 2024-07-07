
rule Trojan_Win32_Snojan_AJS_MTB{
	meta:
		description = "Trojan:Win32/Snojan.AJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 fe 10 8d 8d 98 91 ff ff 0f 43 c8 8a 07 83 c7 02 88 04 0b 8b 9d a8 91 ff ff 43 89 9d a8 91 ff ff 3b fa 74 0e 8b b5 ac 91 ff ff 8b 85 98 91 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}