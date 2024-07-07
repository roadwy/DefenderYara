
rule Trojan_Win32_Malachite_A_bit{
	meta:
		description = "Trojan:Win32/Malachite.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 6f 74 6e 65 74 73 5c 69 6e 66 65 72 6e 61 6c 5f 6d 61 63 68 69 6e 65 32 5c 73 72 63 5c 69 6e 66 65 63 74 2e 76 63 78 70 72 6f 6a } //1 botnets\infernal_machine2\src\infect.vcxproj
		$a_01_1 = {63 6f 70 79 20 2e 2e 5c 72 65 6c 65 61 73 65 5c 76 69 72 2e 62 69 6e 20 62 69 6e 5c 64 72 6f 70 2e 62 69 6e } //1 copy ..\release\vir.bin bin\drop.bin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}