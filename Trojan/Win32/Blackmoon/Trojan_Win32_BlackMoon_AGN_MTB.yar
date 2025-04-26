
rule Trojan_Win32_BlackMoon_AGN_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.AGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 4d 54 78 77 4e 53 51 52 79 53 4f 47 6b 6c 46 56 4a 31 72 4b 79 6c 4f 30 37 47 6b 7c 48 33 37 30 4a 54 49 74 4b 55 37 54 73 61 54 35 4d 69 30 } //1 HMTxwNSQRySOGklFVJ1rKylO07Gk|H370JTItKU7TsaT5Mi0
		$a_01_1 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
		$a_01_2 = {51 51 5f 45 78 69 74 5f 49 6e 66 6f 5f 4d 75 74 65 78 5f } //2 QQ_Exit_Info_Mutex_
		$a_01_3 = {35 42 33 38 33 38 46 35 2d 30 43 38 31 2d 34 36 44 39 2d 41 34 43 30 2d 36 45 41 32 38 43 41 33 45 39 34 32 } //2 5B3838F5-0C81-46D9-A4C0-6EA28CA3E942
		$a_01_4 = {7b 45 32 39 46 46 44 38 46 2d 30 32 38 33 2d 34 37 37 32 2d 38 33 34 41 2d 33 39 46 38 34 30 41 33 38 43 33 45 7d } //1 {E29FFD8F-0283-4772-834A-39F840A38C3E}
		$a_01_5 = {4f 58 34 5c 65 78 6c 6b 69 6c 6c 65 72 2e 62 61 74 } //1 OX4\exlkiller.bat
		$a_01_6 = {72 64 20 2f 73 20 2f 71 20 25 77 69 6e 64 69 72 25 5c 54 65 6d 70 20 26 20 6d 64 20 25 77 69 6e 64 69 72 25 5c 54 65 6d 70 } //1 rd /s /q %windir%\Temp & md %windir%\Temp
		$a_01_7 = {61 70 69 3d 4a 55 71 59 72 67 70 7c 48 33 37 30 4a 57 6c 68 5a 4b 48 69 65 6a 45 32 6c 5a 41 7c 4d 48 31 37 31 43 7c 4d 48 31 37 31 43 } //1 api=JUqYrgp|H370JWlhZKHiejE2lZA|MH171C|MH171C
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}