
rule Virus_Win32_Xorer_gen_A{
	meta:
		description = "Virus:Win32/Xorer.gen!A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0f 00 00 03 00 "
		
	strings :
		$a_01_0 = {6a 6e 6a 65 6a 64 6a 64 6a 69 6a 48 6a 72 6a 65 6a 70 6a 75 6a 53 6a 77 6a 6f 6a 68 6a 53 } //03 00  jnjejdjdjijHjrjejpjujSjwjojhjS
		$a_01_1 = {6a 75 6a 52 6a 6f 6a 74 6a 75 6a 41 6a 65 6a 70 6a 79 6a 54 6a 65 6a 76 6a 69 6a 72 6a 44 6a 6f 6a 4e } //03 00  jujRjojtjujAjejpjyjTjejvjijrjDjojN
		$a_01_2 = {6a 73 6a 2f 50 6a 64 6a 72 50 6a 63 6a 2f 50 6a 65 6a 78 6a 65 6a 2e 6a 64 6a 6d 6a 63 } //03 00  jsj/PjdjrPjcj/Pjejxjej.jdjmjc
		$a_01_3 = {6a 66 6a 69 6a 70 6a 2e 6a 65 6a 6c 6a 69 6a 66 6a 65 6a 67 6a 61 6a 70 } //02 00  jfjijpj.jejljijfjejgjajp
		$a_01_4 = {25 73 5c 64 6e 73 71 2e 64 6c 6c } //01 00  %s\dnsq.dll
		$a_01_5 = {33 36 30 61 6e 74 69 00 } //01 00  㘳愰瑮i
		$a_01_6 = {25 73 5c 30 33 37 35 38 39 2e 6c 6f 67 } //01 00  %s\037589.log
		$a_01_7 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00 } //01 00 
		$a_01_8 = {78 63 67 75 63 76 6e 7a 6e } //01 00  xcgucvnzn
		$a_01_9 = {25 73 5c 4e 65 74 41 70 69 30 30 30 2e 73 79 73 } //01 00  %s\NetApi000.sys
		$a_01_10 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 70 61 67 65 66 69 6c 65 2e 70 69 66 } //01 00  shell\open\Command=pagefile.pif
		$a_01_11 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_01_12 = {2d 72 20 2d 69 6e 75 6c 20 2d 69 62 63 6b 20 2d 79 } //01 00  -r -inul -ibck -y
		$a_01_13 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 53 75 70 65 72 48 69 64 64 65 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden
		$a_01_14 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 46 20 2f 51 20 22 } //00 00  cmd.exe /c del /F /Q "
	condition:
		any of ($a_*)
 
}