
rule Trojan_Win64_WinGoObfusc_TB_MTB{
	meta:
		description = "Trojan:Win64/WinGoObfusc.TB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 6c 24 28 8b 54 24 20 c1 ea 18 0f b6 d2 41 8b 14 97 42 33 54 a0 08 41 c1 ed 08 8b 7c 24 14 44 0f b6 cf 8b 5c 24 1c c1 eb 10 45 0f b6 ed 0f b6 db 33 14 9e 43 33 14 a8 43 33 14 8a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}