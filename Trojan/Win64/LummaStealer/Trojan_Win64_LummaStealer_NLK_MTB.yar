
rule Trojan_Win64_LummaStealer_NLK_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 18 4c 8b c1 b8 4d 5a 00 00 66 39 05 ?? ?? ?? ?? 75 78 48 63 0d ?? ?? ?? ?? 48 8d 15 cd 70 cf ff 48 03 ca } //3
		$a_03_1 = {66 0f 6f 05 8d a4 12 00 48 83 c8 ff f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 12 0f 14 00 f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 1b 0f 14 00 c6 05 ?? ?? ?? ?? 01 b0 01 48 83 c4 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}