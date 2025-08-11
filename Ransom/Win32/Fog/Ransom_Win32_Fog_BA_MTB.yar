
rule Ransom_Win32_Fog_BA_MTB{
	meta:
		description = "Ransom:Win32/Fog.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 50 76 36 20 53 68 65 6c 6c 63 6f 64 65 20 50 61 72 73 69 6e 67 20 46 61 69 6c 65 64 } //1 IPv6 Shellcode Parsing Failed
		$a_01_1 = {4f 42 53 49 44 49 41 4e 4d 49 52 52 4f 52 20 2d 20 50 53 59 4f 50 53 2f 50 53 59 57 41 52 } //1 OBSIDIANMIRROR - PSYOPS/PSYWAR
		$a_01_2 = {52 41 4e 53 4f 4d 4e 4f 54 45 2e 74 78 74 } //1 RANSOMNOTE.txt
		$a_01_3 = {45 78 65 63 75 74 65 64 20 61 6e 74 69 2d 64 65 62 75 67 2d 74 68 72 65 61 64 } //1 Executed anti-debug-thread
		$a_01_4 = {53 61 6e 64 62 6f 78 20 64 65 74 65 63 74 65 64 21 20 45 78 69 74 69 6e 67 20 70 72 6f 63 65 73 73 } //1 Sandbox detected! Exiting process
		$a_01_5 = {44 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 21 20 45 78 69 74 69 6e 67 } //1 Debugger detected! Exiting
		$a_01_6 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 73 65 6e 73 69 74 69 76 65 20 63 68 65 63 6b 20 74 68 72 65 61 64 } //1 Failed to create sensitive check thread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}