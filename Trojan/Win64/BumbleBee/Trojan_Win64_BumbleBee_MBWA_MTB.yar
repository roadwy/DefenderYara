
rule Trojan_Win64_BumbleBee_MBWA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.MBWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 48 8b 05 ?? ?? ?? ?? 44 ?? ?? ?? ff 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? ff c8 31 05 ?? ?? ?? ?? 49 81 fb ?? ?? ?? ?? 0f 8c } //2
		$a_01_1 = {2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 59 59 52 39 31 } //1 搮汬䐀汬敒楧瑳牥敓癲牥夀剙ㄹ
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}