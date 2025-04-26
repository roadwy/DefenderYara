
rule PWS_Win32_Kheagol_D{
	meta:
		description = "PWS:Win32/Kheagol.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {af aa bf aa e5 bb a3 bb f4 a2 af f6 ee b8 ed bd ae b9 f6 ee be ed a6 f6 ee be ed a9 bf b2 bb ae f6 ee be 00 } //5
		$a_01_1 = {43 52 45 44 55 49 2e 64 6c 6c } //1 CREDUI.dll
		$a_01_2 = {43 72 65 64 55 49 50 72 6f 6d 70 74 46 6f 72 43 72 65 64 65 6e 74 69 61 6c 73 } //1 CredUIPromptForCredentials
		$a_01_3 = {50 46 58 49 6d 70 6f 72 74 43 65 72 74 53 74 6f 72 65 } //1 PFXImportCertStore
		$a_01_4 = {68 8d bd c1 3f } //1
		$a_01_5 = {68 37 bd 4f 84 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}