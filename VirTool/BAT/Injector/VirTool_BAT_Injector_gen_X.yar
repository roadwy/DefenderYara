
rule VirTool_BAT_Injector_gen_X{
	meta:
		description = "VirTool:BAT/Injector.gen!X,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 73 73 65 6d 62 6c 79 46 6c 61 67 73 41 74 74 72 69 62 75 74 65 } //1 AssemblyFlagsAttribute
		$a_01_1 = {41 73 73 65 6d 62 6c 79 4e 61 6d 65 46 6c 61 67 73 } //1 AssemblyNameFlags
		$a_01_2 = {43 00 6c 00 61 00 73 00 73 00 4d 00 61 00 69 00 6e 00 } //1 ClassMain
		$a_01_3 = {63 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 43 72 79 70 74 65 78 5c } //2 c:\Users\Administrator\Desktop\Cryptex\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}