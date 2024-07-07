
rule TrojanSpy_AndroidOS_Raddex_YA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Raddex.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_00_0 = {48 65 79 20 52 61 64 39 } //1 Hey Rad9
		$a_00_1 = {52 61 64 64 65 78 5f } //1 Raddex_
		$a_00_2 = {61 73 5f 52 6f 6f 74 } //1 as_Root
		$a_01_3 = {74 65 6b 63 40 50 73 65 74 79 42 65 6c 69 46 } //1 tekc@PsetyBeliF
		$a_01_4 = {59 6f 75 20 63 61 75 73 65 64 20 61 6e 20 65 72 72 6f 72 20 4d 72 2e 52 40 64 64 33 78 } //1 You caused an error Mr.R@dd3x
		$a_01_5 = {48 6d 7a 61 43 6f 6e 74 61 63 74 73 } //1 HmzaContacts
		$a_01_6 = {48 6d 7a 61 53 68 65 6c 6c } //1 HmzaShell
		$a_00_7 = {3c 2f 48 41 4d 5a 41 5f 44 45 4c 49 4d 49 54 45 52 5f 53 54 4f 50 3e } //1 </HAMZA_DELIMITER_STOP>
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}