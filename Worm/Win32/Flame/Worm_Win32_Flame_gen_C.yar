
rule Worm_Win32_Flame_gen_C{
	meta:
		description = "Worm:Win32/Flame.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 48 11 83 c0 0b 0f af c8 8b d1 c1 ea 08 8b c2 33 c1 c1 e8 10 33 c2 33 c1 } //4
		$a_03_1 = {8a 06 56 88 47 ff ff 15 ?? ?? ?? ?? 80 3e 63 88 07 7c 5a 33 c0 53 } //2
		$a_01_2 = {52 70 63 4e 73 42 69 6e 64 69 6e 67 49 6e 69 74 } //1 RpcNsBindingInit
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}