
rule Trojan_Win32_Offloader_KAC_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 62 65 61 64 6f 62 73 65 72 76 61 74 69 6f 6e 2e 73 69 74 65 2f 72 6c 6f 2e 70 68 70 } //://beadobservation.site/rlo.php  02 00 
		$a_80_1 = {56 45 52 59 53 49 4c 45 4e 54 20 2f 53 55 50 50 52 45 53 53 4d 53 47 42 4f 58 45 53 } //VERYSILENT /SUPPRESSMSGBOXES  01 00 
		$a_80_2 = {6f 6e 6c 79 2f 70 70 62 61 } //only/ppba  00 00 
	condition:
		any of ($a_*)
 
}