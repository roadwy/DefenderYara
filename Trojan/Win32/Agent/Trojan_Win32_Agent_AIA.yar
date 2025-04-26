
rule Trojan_Win32_Agent_AIA{
	meta:
		description = "Trojan:Win32/Agent.AIA,SIGNATURE_TYPE_PEHSTR,6e 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 46 55 43 4b 3d 46 55 43 4b 75 } //100
		$a_01_1 = {46 55 43 4b 3d 46 55 43 4b } //10 FUCK=FUCK
		$a_01_2 = {66 75 63 6b 61 6c 6c 62 6c 79 61 } //10 fuckallblya
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=100
 
}