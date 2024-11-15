
rule Trojan_BAT_AgentTesla_GI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 46 45 51 52 42 32 36 58 33 50 44 45 44 46 57 56 42 4e 4e 7a 37 5a 35 4c 71 76 4a 61 59 68 42 71 7a 4d 50 49 51 62 39 33 59 70 6c 67 4e 48 50 4d 34 31 38 39 6c 49 5a 63 56 52 55 4b 49 6b 76 70 44 78 36 58 79 54 79 49 6d 42 65 32 4a 57 71 47 6d 50 4a 59 4f 47 5a 72 75 4b 64 34 63 50 48 77 44 43 6e 67 33 77 } //2 RFEQRB26X3PDEDFWVBNNz7Z5LqvJaYhBqzMPIQb93YplgNHPM4189lIZcVRUKIkvpDx6XyTyImBe2JWqGmPJYOGZruKd4cPHwDCng3w
		$a_01_1 = {79 74 6a 35 39 64 32 37 6d 37 34 37 6e 64 6c 75 34 6c 76 6a 32 7a 65 78 35 6e 75 66 61 6c 6a 76 } //2 ytj59d27m747ndlu4lvj2zex5nufaljv
		$a_01_2 = {34 37 6a 75 72 75 63 34 32 6c 36 71 38 76 74 6c 65 38 71 61 66 6c 7a 65 75 65 34 73 6e 70 65 38 } //2 47juruc42l6q8vtle8qaflzeue4snpe8
		$a_01_3 = {71 39 67 63 6a 73 35 63 64 7a 75 38 61 66 79 35 79 75 6e 37 33 67 37 73 62 75 32 38 36 75 6d } //2 q9gcjs5cdzu8afy5yun73g7sbu286um
		$a_01_4 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_5 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_6 = {47 65 74 5f 55 73 65 72 44 6f 6d 61 69 6e 4e 61 6d 65 } //1 Get_UserDomainName
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}