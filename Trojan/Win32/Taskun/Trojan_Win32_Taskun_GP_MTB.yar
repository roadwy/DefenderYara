
rule Trojan_Win32_Taskun_GP_MTB{
	meta:
		description = "Trojan:Win32/Taskun.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 76 61 6c 68 61 6c 6c 61 2e 69 70 64 6e 73 2e 68 75 3a 38 30 2f 72 65 67 63 68 6b 2e 65 78 65 } //1 http://valhalla.ipdns.hu:80/regchk.exe
		$a_81_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 55 70 5c 72 65 67 63 68 6b 2e 65 78 65 } //1 \Microsoft\Windows\Start Menu\Programs\StartUp\regchk.exe
		$a_81_2 = {67 61 74 65 77 61 79 40 76 61 6c 68 61 6c 6c 61 2e 69 70 64 6e 73 2e 68 75 3a 2f 68 6f 6d 65 2f 67 61 74 65 77 61 79 2f 75 70 6c 6f 61 64 2f } //1 gateway@valhalla.ipdns.hu:/home/gateway/upload/
		$a_81_3 = {68 74 74 70 3a 2f 2f 76 61 6c 68 61 6c 6c 61 2e 69 70 64 6e 73 2e 68 75 3a 38 30 2f 70 75 74 2e 70 68 70 } //1 http://valhalla.ipdns.hu:80/put.php
		$a_81_4 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 4a 6f 68 6e 44 6f 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 41 64 6f 62 65 75 70 64 61 74 65 72 2e 62 69 6e } //1 C:\Documents and Settings\JohnDoe\Application Data\Adobeupdater.bin
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}