
rule Worm_Win32_VBInject_GXZ_MTB{
	meta:
		description = "Worm:Win32/VBInject.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {4e 48 82 31 8a 74 ?? 22 7c 3b 80 94 07 } //10
		$a_80_1 = {6e 45 77 62 30 52 6e 2e 65 78 65 } //nEwb0Rn.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}