
rule Worm_Win32_Autorun_gen_AY{
	meta:
		description = "Worm:Win32/Autorun.gen!AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 73 63 72 69 70 74 20 63 3a 5c 50 72 6f 67 72 61 7e 31 5c 49 6e 74 65 72 6e 7e 31 5c 50 4c 55 47 49 4e 53 5c 73 68 65 6c 6c 7e 31 5c 64 6f 77 6e 2e 76 62 73 } //1 cscript c:\Progra~1\Intern~1\PLUGINS\shell~1\down.vbs
		$a_03_1 = {f7 d8 1b c0 f7 d8 23 f0 f7 de 1b f6 f7 de 8b 45 d8 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? f7 d8 1b c0 f7 d8 23 f0 85 f6 75 50 c7 45 fc 0a 00 00 00 68 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}