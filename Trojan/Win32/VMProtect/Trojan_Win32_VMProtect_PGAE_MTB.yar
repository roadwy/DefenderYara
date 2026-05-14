
rule Trojan_Win32_VMProtect_PGAE_MTB{
	meta:
		description = "Trojan:Win32/VMProtect.PGAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 67 69 77 65 66 6b 77 66 69 77 } //1 \giwefkwfiw
		$a_80_1 = {7a 75 68 61 6f 63 6c 69 65 6e 74 2e 65 78 65 } //zuhaoclient.exe  1
		$a_01_2 = {43 3a 5c 7a 75 68 61 6f } //1 C:\zuhao
		$a_01_3 = {5c 4c 69 74 65 43 6c 69 65 6e 74 2e 65 78 65 } //1 \LiteClient.exe
		$a_01_4 = {5c 74 65 6c 6e 65 74 2e 65 78 65 } //1 \telnet.exe
		$a_01_5 = {47 44 49 2b 20 48 6f 6f 6b 20 57 69 6e 64 6f 77 20 43 6c 61 73 73 } //1 GDI+ Hook Window Class
		$a_01_6 = {50 72 6f 67 6d 61 6e 00 53 48 45 4c 4c 44 4c 4c 5f 44 65 66 56 69 65 77 } //1 牐杯慭n䡓䱅䑌䱌䑟晥楖睥
		$a_01_7 = {5c 53 46 48 6f 6f 6b 5c 72 65 6c 65 61 73 65 5c 47 50 2e 70 64 62 } //1 \SFHook\release\GP.pdb
		$a_01_8 = {5c 70 69 70 65 5c 7b 32 33 41 39 35 32 33 43 2d 33 42 41 38 2d 34 44 33 32 2d 38 36 43 43 2d 33 45 32 44 32 37 39 37 43 31 38 45 7d } //1 \pipe\{23A9523C-3BA8-4D32-86CC-3E2D2797C18E}
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}