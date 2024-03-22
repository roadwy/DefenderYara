
rule Trojan_Win32_Offloader_GZK_MTB{
	meta:
		description = "Trojan:Win32/Offloader.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 00 74 00 6f 00 2e 00 66 00 61 00 72 00 6d 00 73 00 63 00 65 00 6e 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 } //02 00  sto.farmscene.website
		$a_01_1 = {00 68 00 75 00 6d 00 6f 00 72 00 73 00 63 00 69 00 65 00 6e 00 63 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 61 00 73 00 69 00 6b 00 6f 00 2e 00 70 00 68 00 70 } //01 00  栀甀洀漀爀猀挀椀攀渀挀攀⸀眀攀戀猀椀琀攀⼀愀猀椀欀漀⸀瀀栀瀀
		$a_80_2 = {6f 6e 6c 79 2f 70 70 62 61 } //only/ppba  00 00 
	condition:
		any of ($a_*)
 
}