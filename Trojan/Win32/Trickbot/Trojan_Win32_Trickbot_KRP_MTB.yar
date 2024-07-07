
rule Trojan_Win32_Trickbot_KRP_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KRP!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 0c 10 8b 55 f4 0f b6 84 15 90 01 02 ff ff 33 c1 8b 4d f4 88 84 0d 90 01 02 ff ff eb 90 09 06 00 8b 85 90 01 02 ff ff 90 00 } //2
		$a_01_1 = {58 57 46 54 50 48 46 4d 57 4f 4d 5a 51 47 49 53 5a 5a 5a 42 43 44 49 41 51 51 4a 54 52 4c 44 47 43 4f 43 52 43 4f 52 48 4d 4d 4a 4b 54 52 57 59 41 4a 48 52 44 56 55 54 4f 46 43 59 59 4d 55 4b 4c } //2 XWFTPHFMWOMZQGISZZZBCDIAQQJTRLDGCOCRCORHMMJKTRWYAJHRDVUTOFCYYMUKL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}