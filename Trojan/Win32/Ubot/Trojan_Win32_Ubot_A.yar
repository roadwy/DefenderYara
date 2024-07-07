
rule Trojan_Win32_Ubot_A{
	meta:
		description = "Trojan:Win32/Ubot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 72 6f 6c 3d 74 72 6f 6c 26 75 73 65 72 61 6e 64 70 63 3d 25 73 26 61 64 6d 69 6e 3d 25 73 26 6f 73 3d 25 73 26 63 70 75 3d 25 73 26 67 70 75 3d 25 73 26 62 61 74 74 65 72 79 3d 25 2e 31 73 26 69 64 3d 25 73 26 76 65 72 73 69 6f 6e 3d 25 73 26 64 6f 74 6e 65 74 3d 25 73 } //1 trol=trol&userandpc=%s&admin=%s&os=%s&cpu=%s&gpu=%s&battery=%.1s&id=%s&version=%s&dotnet=%s
		$a_01_1 = {2f 62 6f 74 73 31 2f 72 75 6e 2e 70 68 70 } //1 /bots1/run.php
		$a_01_2 = {66 63 35 64 66 63 61 64 37 33 38 33 35 38 61 30 63 62 62 35 39 62 66 30 34 37 38 33 34 30 61 31 } //1 fc5dfcad738358a0cbb59bf0478340a1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}