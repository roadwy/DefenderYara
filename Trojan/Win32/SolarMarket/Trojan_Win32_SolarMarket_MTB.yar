
rule Trojan_Win32_SolarMarket_MTB{
	meta:
		description = "Trojan:Win32/SolarMarket!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {3d 00 27 00 68 00 42 00 6a 00 6e 00 4b 00 54 00 71 00 66 00 58 00 6f 00 45 00 69 00 49 00 48 00 79 00 55 00 6d 00 53 00 77 00 51 00 62 00 46 00 75 00 74 00 50 00 76 00 65 00 4f 00 52 00 7a 00 64 00 59 00 4a 00 41 00 63 00 73 00 61 00 78 00 70 00 44 00 57 00 56 00 47 00 4c 00 43 00 72 00 4e 00 4d 00 67 00 6c 00 5a 00 6b 00 27 00 3b 00 24 00 } //1 ='hBjnKTqfXoEiIHyUmSwQbFutPveORzdYJAcsaxpDWVGLCrNMglZk';$
		$a_01_1 = {3d 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 49 00 4f 00 2e 00 46 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 52 00 65 00 61 00 64 00 41 00 6c 00 6c 00 54 00 65 00 78 00 74 00 28 00 24 00 } //1 =[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($
		$a_01_2 = {29 00 29 00 3b 00 72 00 65 00 6d 00 6f 00 76 00 65 00 2d 00 69 00 74 00 65 00 6d 00 20 00 24 00 } //1 ));remove-item $
		$a_01_3 = {3b 00 66 00 6f 00 72 00 28 00 24 00 69 00 3d 00 30 00 3b 00 24 00 69 00 20 00 2d 00 6c 00 74 00 20 00 24 00 } //1 ;for($i=0;$i -lt $
		$a_01_4 = {2e 00 63 00 6f 00 75 00 6e 00 74 00 3b 00 29 00 7b 00 66 00 6f 00 72 00 28 00 24 00 6a 00 3d 00 30 00 3b 00 24 00 6a 00 20 00 2d 00 6c 00 74 00 20 00 24 00 } //1 .count;){for($j=0;$j -lt $
		$a_01_5 = {2e 00 6c 00 65 00 6e 00 67 00 74 00 68 00 3b 00 24 00 6a 00 2b 00 2b 00 29 00 7b 00 24 00 } //1 .length;$j++){$
		$a_01_6 = {5b 00 24 00 69 00 5d 00 3d 00 24 00 } //1 [$i]=$
		$a_01_7 = {5b 00 24 00 69 00 5d 00 20 00 2d 00 62 00 78 00 6f 00 72 00 20 00 24 00 } //1 [$i] -bxor $
		$a_01_8 = {5b 00 24 00 6a 00 5d 00 3b 00 24 00 69 00 2b 00 2b 00 3b 00 69 00 66 00 28 00 24 00 69 00 20 00 2d 00 67 00 65 00 20 00 24 00 } //1 [$j];$i++;if($i -ge $
		$a_01_9 = {2e 00 63 00 6f 00 75 00 6e 00 74 00 29 00 7b 00 24 00 6a 00 3d 00 24 00 } //1 .count){$j=$
		$a_01_10 = {2e 00 6c 00 65 00 6e 00 67 00 74 00 68 00 7d 00 7d 00 7d 00 3b 00 24 00 } //1 .length}}};$
		$a_01_11 = {3d 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 54 00 46 00 38 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 =[System.Text.Encoding]::UTF8.GetString($
		$a_01_12 = {29 00 3b 00 69 00 65 00 78 00 20 00 24 00 } //1 );iex $
		$a_01_13 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 } //1 -command "
		$a_01_14 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}