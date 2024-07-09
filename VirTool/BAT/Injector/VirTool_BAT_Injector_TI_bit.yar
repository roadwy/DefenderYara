
rule VirTool_BAT_Injector_TI_bit{
	meta:
		description = "VirTool:BAT/Injector.TI!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {28 1c 00 00 06 03 6f 12 00 00 0a 74 01 00 00 1b 0a 16 0b 2b 15 7e 01 00 00 04 06 07 91 1f ?? 61 d2 6f 13 00 00 0a 07 17 58 0b 07 06 8e 69 17 59 32 e3 16 2a } //2
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 00 41 64 64 00 54 6f 41 72 72 61 79 00 41 73 73 65 6d 62 6c 79 00 4c 6f 61 64 00 } //2 敇佴橢捥t摁d潔牁慲y獁敳扭祬䰀慯d
		$a_01_2 = {5f 54 65 78 74 43 68 61 6e 67 65 64 } //1 _TextChanged
		$a_01_3 = {5f 53 65 6c 65 63 74 65 64 56 61 6c 75 65 43 68 61 6e 67 65 64 } //1 _SelectedValueChanged
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}