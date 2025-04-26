
rule Trojan_Win32_Scar_MA_MTB{
	meta:
		description = "Trojan:Win32/Scar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //1 Microsoft\Windows\Start Menu\Programs\Startup
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 66 20 2d 74 20 31 } //1 shutdown -s -f -t 1
		$a_01_2 = {63 6f 70 79 20 2f 79 } //1 copy /y
		$a_01_3 = {55 73 65 72 73 5c 67 68 69 67 6f 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 73 68 75 74 64 6f 77 6e 5c 52 65 6c 65 61 73 65 5c 73 68 75 74 64 6f 77 6e 2e 70 64 62 } //1 Users\ghigo\source\repos\shutdown\Release\shutdown.pdb
		$a_01_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}