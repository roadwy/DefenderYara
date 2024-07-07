
rule Backdoor_Win32_Drateam_gen_A{
	meta:
		description = "Backdoor:Win32/Drateam.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 0f 00 00 00 4d 53 47 7c c4 bf c2 bc b2 bb b4 e6 d4 da 21 00 } //1
		$a_01_1 = {ff ff ff ff 0d 00 00 00 4d 53 47 7c ce de b7 a8 bb f1 c8 a1 21 00 } //1
		$a_01_2 = {d4 ca d0 ed b4 cb b6 af d7 f7 00 } //1
		$a_01_3 = {ff ff ff ff 07 00 00 00 65 78 65 2e 70 76 61 } //1
		$a_01_4 = {ff ff ff ff 0c 00 00 00 65 78 65 2e 6e 72 6b 32 33 64 6f 6e } //1
		$a_03_5 = {68 01 02 00 00 90 01 01 e8 90 01 04 6a 00 6a 00 68 02 02 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}