
rule Trojan_Win32_Injector_AMTB{
	meta:
		description = "Trojan:Win32/Injector!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 4f 4d 53 50 45 43 3d 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 } //COMSPEC=C:\WINDOWS\system32\cmd.exe  1
		$a_80_1 = {58 3a 5c 44 20 42 41 43 4b 55 50 20 32 39 30 33 32 30 31 34 5c 50 72 6f 6a 65 63 74 73 5c 61 6c 69 5c 70 72 6f 6a 5c 4d 69 6e 69 20 72 61 74 5c 54 4d 53 20 43 6f 6d 70 6f 6e 65 6e 74 20 50 61 63 6b 20 32 5c 54 4d 53 20 43 6f 6d 70 6f 6e 65 6e 74 20 50 61 63 6b 5c 41 43 58 50 56 53 2e 70 61 73 } //X:\D BACKUP 29032014\Projects\ali\proj\Mini rat\TMS Component Pack 2\TMS Component Pack\ACXPVS.pas  1
		$a_80_2 = {58 3a 5c 44 20 42 41 43 4b 55 50 20 32 39 30 33 32 30 31 34 5c 50 72 6f 6a 65 63 74 73 5c 61 6c 69 5c 70 72 6f 6a 5c 4d 69 6e 69 20 72 61 74 5c 54 4d 53 20 43 6f 6d 70 6f 6e 65 6e 74 20 50 61 63 6b 20 32 5c 54 4d 53 20 43 6f 6d 70 6f 6e 65 6e 74 20 50 61 63 6b 5c 41 43 4c 64 64 2e 70 61 73 } //X:\D BACKUP 29032014\Projects\ali\proj\Mini rat\TMS Component Pack 2\TMS Component Pack\ACLdd.pas  1
		$a_80_3 = {58 3a 5c 44 20 42 41 43 4b 55 50 20 32 39 30 33 32 30 31 34 5c 50 72 6f 6a 65 63 74 73 5c 61 6c 6d 64 65 76 2e 42 75 73 69 6e 65 73 73 53 6b 69 6e 20 76 39 20 28 6c 61 74 65 73 74 29 5c 62 73 66 39 36 30 5c 62 73 66 39 36 30 5c 62 73 66 39 36 30 5c 62 73 45 66 66 65 63 74 73 2e 70 61 73 } //X:\D BACKUP 29032014\Projects\almdev.BusinessSkin v9 (latest)\bsf960\bsf960\bsf960\bsEffects.pas  1
		$a_80_4 = {58 3a 5c 44 20 42 41 43 4b 55 50 20 32 39 30 33 32 30 31 34 5c 4a 56 43 4c 33 34 39 43 6f 6d 70 6c 65 74 65 4a 43 4c 32 37 2d 42 75 69 6c 64 35 36 37 36 5c 6a 63 6c 5c 73 6f 75 72 63 65 5c 63 6f 6d 6d 6f 6e 5c 4a 63 6c 53 74 72 69 6e 67 73 2e 70 61 73 } //X:\D BACKUP 29032014\JVCL349CompleteJCL27-Build5676\jcl\source\common\JclStrings.pas  1
		$a_80_5 = {43 72 65 61 74 65 54 68 72 65 61 64 7c 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 77 6f 77 36 34 5c 69 65 78 70 72 65 73 73 2e 65 78 65 } //CreateThread|C:\windows\syswow64\iexpress.exe  1
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=6
 
}