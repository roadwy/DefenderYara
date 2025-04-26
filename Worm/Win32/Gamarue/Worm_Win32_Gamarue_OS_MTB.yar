
rule Worm_Win32_Gamarue_OS_MTB{
	meta:
		description = "Worm:Win32/Gamarue.OS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3a 5c 6d 61 72 69 65 ?? 5c 64 65 76 69 6c 6d 61 6e 5c 78 78 78 78 78 5c 63 61 74 66 69 67 68 74 5c 69 79 67 6d 79 67 6a 6b 78 74 79 75 2e 70 64 62 } //1
		$a_00_1 = {69 79 67 6d 79 67 6a 6b 78 74 79 75 2e 64 6c 6c } //1 iygmygjkxtyu.dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}