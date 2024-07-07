
rule Trojan_Win32_Delf_SA_MTB{
	meta:
		description = "Trojan:Win32/Delf.SA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 20 61 64 76 70 61 63 6b 2e 64 6c 6c 2c 44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 20 25 73 } //1 rundll32 advpack.dll,DelNodeRunDLL32 %s
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 45 78 5c 39 32 30 } //1 \Microsoft\Windows\CurrentVersion\RunOnceEx\920
		$a_01_2 = {5c 64 78 6d 69 6e 69 61 78 2e 63 61 62 } //1 \dxminiax.cab
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 61 63 6c 73 2e 65 78 65 } //1 C:\WINDOWS\system32\cacls.exe
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 61 73 72 5f 70 66 75 2e 65 78 65 } //1 C:\WINDOWS\system32\asr_pfu.exe
		$a_01_5 = {46 3a 5c 4f 66 66 69 63 65 5c 54 61 72 67 65 74 5c 78 38 36 5c 73 68 69 70 5c 70 6f 73 74 63 32 72 5c 78 2d 6e 6f 6e 65 5c 77 6f 72 64 63 6f 6e 76 } //5 F:\Office\Target\x86\ship\postc2r\x-none\wordconv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5) >=8
 
}