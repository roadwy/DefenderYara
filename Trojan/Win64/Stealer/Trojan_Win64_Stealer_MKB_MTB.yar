
rule Trojan_Win64_Stealer_MKB_MTB{
	meta:
		description = "Trojan:Win64/Stealer.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 78 63 6f 70 79 20 2f 45 20 2f 49 20 2f 48 20 2f 59 20 22 25 73 22 20 22 25 73 5c 74 64 61 74 61 } //15 cmd.exe /c xcopy /E /I /H /Y "%s" "%s\tdata
		$a_01_1 = {4c 6f 67 69 6e 5f 44 61 74 61 } //10 Login_Data
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 46 69 6c 65 20 22 25 73 } //10 cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "%s
		$a_01_3 = {25 73 62 72 6f 77 73 65 72 5f 64 61 74 61 2e 7a 69 70 } //10 %sbrowser_data.zip
		$a_01_4 = {25 73 74 65 6c 65 67 72 61 6d 5f 64 61 74 61 2e 7a 69 70 } //10 %stelegram_data.zip
		$a_01_5 = {25 73 5c 25 73 5f 64 65 63 72 79 70 74 65 64 } //5 %s\%s_decrypted
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*5) >=60
 
}