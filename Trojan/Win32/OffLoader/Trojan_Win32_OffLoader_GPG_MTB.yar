
rule Trojan_Win32_OffLoader_GPG_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_80_0 = {67 61 6c 61 6e 64 73 6b 69 79 68 65 72 35 2e 63 6f 6d 2f 70 72 69 76 61 63 79 } //galandskiyher5.com/privacy  02 00 
		$a_80_1 = {64 69 67 69 74 61 6c 70 75 6c 73 65 64 61 74 61 2e 63 6f 6d 2f 74 6f 73 } //digitalpulsedata.com/tos  00 00 
	condition:
		any of ($a_*)
 
}