
rule Backdoor_Win32_Poison_BD{
	meta:
		description = "Backdoor:Win32/Poison.BD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ?? ?? 40 83 f8 40 72 ea 33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 4c 05 ?? 40 83 f8 40 72 ed } //5
		$a_01_1 = {5c 5c 2e 5c 4c 50 52 53 00 00 00 00 5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 90 02 10 5f 6d 61 69 6c 73 6c 6f 74 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}