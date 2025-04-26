
rule Trojan_BAT_AgentTesla_NYV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 41 39 34 38 30 32 46 38 2d 37 41 37 45 2d 34 44 34 38 2d 38 33 36 45 2d 30 35 33 30 34 34 39 41 46 35 33 33 } //1 $A94802F8-7A7E-4D48-836E-0530449AF533
		$a_01_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {4b 6f 65 6e 69 67 73 65 67 67 43 43 58 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 KoenigseggCCX.Properties.Resources.resource
		$a_01_4 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //1 GetDelegateForFunctionPointer
		$a_01_5 = {57 bf a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 f4 00 00 00 3d 00 00 00 f3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}