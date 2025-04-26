
rule Worm_Win32_Mira_A_ibt{
	meta:
		description = "Worm:Win32/Mira.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 53 61 61 61 61 6c 61 6d 6d 5c 4d 69 72 61 2e 68 } //1 Application Data\Saaaalamm\Mira.h
		$a_01_1 = {c6 85 79 ff ff ff 3a c6 85 7a ff ff ff 5c c6 85 7b ff ff ff 4d c6 85 7c ff ff ff 69 c6 85 7d ff ff ff 72 c6 85 7e ff ff ff 61 } //1
		$a_00_2 = {80 bc 28 78 ff ff ff 65 75 4b 0f bf 05 14 20 44 00 80 bc 28 77 ff ff ff 78 75 3a 0f bf 05 14 20 44 00 80 bc 28 76 ff ff ff 65 75 29 0f bf 05 14 20 44 00 80 bc 28 75 ff ff ff 2e 75 18 0f bf 05 14 20 44 00 80 bc 28 74 ff ff ff 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}