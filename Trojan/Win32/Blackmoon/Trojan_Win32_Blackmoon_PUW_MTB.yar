
rule Trojan_Win32_Blackmoon_PUW_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.PUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
		$a_01_1 = {33 61 35 63 39 66 32 37 62 61 30 32 61 65 32 66 30 31 31 38 38 66 32 37 61 35 32 39 36 64 35 64 } //1 3a5c9f27ba02ae2f01188f27a5296d5d
		$a_01_2 = {42 63 6e 54 70 31 68 30 64 6e 4d 46 64 4c 6c 6d } //1 BcnTp1h0dnMFdLlm
		$a_01_3 = {65 62 39 61 64 63 32 37 34 36 39 61 34 31 37 35 66 37 34 30 66 36 33 32 64 37 39 65 36 63 63 64 } //1 eb9adc27469a4175f740f632d79e6ccd
		$a_01_4 = {2f 2f 59 4a 57 4a 2e 63 6f 6d 2f 3f 74 79 70 65 3d 73 74 61 72 74 } //1 //YJWJ.com/?type=start
		$a_01_5 = {2f 2f 79 6a 77 6a 5f 72 65 63 6f 72 64 2e 67 75 61 6e 6c 69 79 75 61 6e 67 6f 6e 67 2e 63 6f 6d 3a 36 30 30 32 } //1 //yjwj_record.guanliyuangong.com:6002
		$a_01_6 = {2f 61 70 69 31 30 30 2e 70 68 70 3f 66 75 6e 3d 70 6f 72 74 26 6e 61 6d 65 3d 74 63 70 } //1 /api100.php?fun=port&name=tcp
		$a_01_7 = {2f 61 70 69 31 30 30 2e 70 68 70 3f 66 75 6e 3d 70 6f 72 74 26 6e 61 6d 65 3d 68 74 74 70 } //1 /api100.php?fun=port&name=http
		$a_01_8 = {2f 61 70 69 31 30 30 2e 70 68 70 3f 66 75 6e 3d 70 6f 72 74 26 6e 61 6d 65 3d 63 61 73 68 } //1 /api100.php?fun=port&name=cash
		$a_01_9 = {2f 61 70 69 31 30 30 2e 70 68 70 3f 66 75 6e 3d 70 6f 72 74 26 6e 61 6d 65 3d 63 61 73 68 77 65 62 } //1 /api100.php?fun=port&name=cashweb
		$a_01_10 = {2f 61 70 69 31 30 30 2e 70 68 70 3f 66 75 6e 3d 70 6f 72 74 26 6e 61 6d 65 3d 73 73 6c } //1 /api100.php?fun=port&name=ssl
		$a_01_11 = {2f 2f 61 70 69 2e 62 61 72 2e 31 36 33 2e 63 6f 6d 2f 6e 65 74 62 61 72 2d 61 70 69 2f 61 70 69 2f 6f 70 65 6e 2f 67 61 6d 65 44 61 74 61 56 32 2f 71 75 65 72 79 4d 61 74 63 68 52 65 73 75 6c 74 } //1 //api.bar.163.com/netbar-api/api/open/gameDataV2/queryMatchResult
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}