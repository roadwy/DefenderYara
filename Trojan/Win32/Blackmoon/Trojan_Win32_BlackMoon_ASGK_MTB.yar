
rule Trojan_Win32_BlackMoon_ASGK_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ASGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 b8 32 63 47 00 89 45 f4 8d 45 f4 50 6a 01 b8 3c 63 47 00 89 45 f0 8d 45 f0 50 8d 45 fc 50 8b 04 24 8b 00 8b 00 ff 90 e0 00 00 00 8b 5d f0 85 db } //5
		$a_01_1 = {83 c4 04 6a 00 6a 00 6a 00 68 31 00 01 00 6a 00 ff 75 d0 68 02 00 00 00 bb 90 09 00 00 e8 } //2
		$a_03_2 = {68 25 00 00 00 68 15 4d 05 04 68 06 00 00 00 e8 ?? ?? 04 00 83 c4 0c e9 } //2
		$a_01_3 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 } //1 BlackMoon RunTime
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}
rule Trojan_Win32_BlackMoon_ASGK_MTB_2{
	meta:
		description = "Trojan:Win32/BlackMoon.ASGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0a 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 10 51 6a 00 50 52 6a 00 6a 00 ff 15 ?? ?? ?? 00 8b 54 24 0c 33 c9 85 c0 0f 95 c1 } //2
		$a_03_1 = {8b 49 0c 33 c0 83 fe 05 55 0f 95 c0 48 57 25 ?? ?? ?? 00 52 51 50 6a 00 ff 15 ?? ?? ?? 00 5f 5e 5d c3 } //2
		$a_03_2 = {68 84 03 00 00 b8 ?? ?? ?? 00 89 45 fc 8d 45 fc 50 ff 35 } //2
		$a_01_3 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
		$a_01_4 = {40 38 77 66 77 66 65 77 66 77 66 77 } //1 @8wfwfewfwfw
		$a_01_5 = {5c 63 66 73 76 2e 69 6e 69 } //1 \cfsv.ini
		$a_01_6 = {77 61 71 69 61 6e 67 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 2f 75 72 6c 2f 73 68 6f 72 74 65 6e } //1 waqiang.com/index.php/url/shorten
		$a_01_7 = {38 39 38 37 35 35 33 38 35 36 32 } //1 89875538562
		$a_01_8 = {6e 62 2e 63 64 79 67 62 79 2e 63 6f 6d } //1 nb.cdygby.com
		$a_01_9 = {73 67 77 33 75 67 32 33 32 67 67 } //1 sgw3ug232gg
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=13
 
}