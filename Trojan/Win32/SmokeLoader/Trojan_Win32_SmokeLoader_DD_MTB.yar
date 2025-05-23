
rule Trojan_Win32_SmokeLoader_DD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 d8 03 45 ac 03 45 e8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 5d b0 8b 45 ec 8b 55 b0 31 10 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_DD_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 00 6f 00 6c 00 65 00 6c 00 61 00 62 00 61 00 70 00 61 00 77 00 20 00 73 00 75 00 77 00 65 00 6c 00 69 00 63 00 65 00 6b 00 65 00 7a 00 69 00 79 00 61 00 76 00 69 00 6a 00 65 00 78 00 6f 00 77 00 69 00 68 00 75 00 6a 00 65 00 78 00 65 00 74 00 } //1 xolelabapaw suwelicekeziyavijexowihujexet
		$a_01_1 = {79 00 61 00 73 00 65 00 67 00 61 00 79 00 65 00 20 00 6a 00 61 00 77 00 65 00 74 00 65 00 77 00 20 00 78 00 75 00 6a 00 6f 00 66 00 69 00 66 00 69 00 66 00 61 00 76 00 75 00 6a 00 6f 00 6a 00 65 00 79 00 6f 00 72 00 69 00 } //1 yasegaye jawetew xujofififavujojeyori
		$a_01_2 = {73 00 65 00 63 00 6f 00 62 00 61 00 77 00 65 00 6a 00 69 00 77 00 6f 00 66 00 75 00 72 00 6f 00 62 00 65 00 6a 00 69 00 66 00 69 00 6a 00 65 00 64 00 61 00 68 00 69 00 64 00 65 00 70 00 6f 00 64 00 69 00 7a 00 6f 00 62 00 65 00 6b 00 75 00 62 00 6f 00 76 00 65 00 64 00 61 00 62 00 61 00 63 00 65 00 63 00 } //1 secobawejiwofurobejifijedahidepodizobekubovedabacec
		$a_01_3 = {79 00 6f 00 6a 00 75 00 6e 00 6f 00 63 00 61 00 6c 00 6f 00 6c 00 75 00 76 00 75 00 70 00 6f 00 64 00 65 00 7a 00 69 00 62 00 65 00 63 00 6f 00 68 00 69 00 7a 00 61 00 77 00 69 00 68 00 20 00 66 00 65 00 73 00 6f 00 79 00 65 00 62 00 69 00 74 00 61 00 73 00 75 00 6a 00 69 00 6d 00 6f 00 64 00 6f 00 63 00 65 00 64 00 61 00 6b 00 61 00 76 00 61 00 72 00 } //1 yojunocaloluvupodezibecohizawih fesoyebitasujimodocedakavar
		$a_01_4 = {4a 00 61 00 6a 00 20 00 6a 00 75 00 73 00 61 00 7a 00 6f 00 7a 00 75 00 20 00 77 00 61 00 63 00 69 00 7a 00 69 00 6a 00 61 00 6c 00 61 00 63 00 69 00 20 00 70 00 61 00 77 00 69 00 7a 00 65 00 64 00 75 00 70 00 65 00 62 00 65 00 79 00 61 00 72 00 65 00 7a 00 69 00 70 00 75 00 6d 00 65 00 6a 00 65 00 78 00 75 00 6d 00 6f 00 6d 00 69 00 76 00 } //1 Jaj jusazozu wacizijalaci pawizedupebeyarezipumejexumomiv
		$a_01_5 = {76 00 65 00 76 00 6f 00 68 00 69 00 64 00 61 00 77 00 75 00 70 00 75 00 6a 00 75 00 63 00 65 00 78 00 65 00 6b 00 75 00 78 00 75 00 6c 00 61 00 68 00 61 00 79 00 6f 00 7a 00 65 00 7a 00 75 00 20 00 6a 00 61 00 73 00 65 00 7a 00 61 00 77 00 75 00 70 00 75 00 6e 00 69 00 79 00 75 00 74 00 } //1 vevohidawupujucexekuxulahayozezu jasezawupuniyut
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}