
rule Trojan_Win32_Emotetcrypt_IT_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {6d 45 79 36 4c 71 6f 59 54 21 5f 66 57 24 6f 70 23 6b 31 57 76 4c 5f 36 74 2b 65 33 4d 72 71 66 29 3c 54 44 } //1 mEy6LqoYT!_fW$op#k1WvL_6t+e3Mrqf)<TD
		$a_01_2 = {75 53 69 63 25 6d 34 76 4d 5a 5f 4b 4e 36 7a 48 5a 32 6f 23 2a 7a 5e 69 3c 45 49 3f 6e 23 4e 67 73 2a 6d 71 61 6e 75 6b 6c 44 4f 59 6f 6a 49 70 71 52 67 4f 6a 51 68 34 21 38 54 50 53 31 5a 6a 53 51 } //1 uSic%m4vMZ_KN6zHZ2o#*z^i<EI?n#Ngs*mqanuklDOYojIpqRgOjQh4!8TPS1ZjSQ
		$a_01_3 = {25 21 63 78 2a 6b 78 62 3f 5f 74 25 45 30 5f 57 72 54 66 69 61 6f 2b 55 6e 23 6b 26 57 70 5e 4f 6d 6a 3c 40 41 5f 5a 28 72 63 46 38 76 6a 34 51 55 72 } //1 %!cx*kxb?_t%E0_WrTfiao+Un#k&Wp^Omj<@A_Z(rcF8vj4QUr
		$a_01_4 = {4b 47 76 4e 73 64 28 76 26 43 6b 45 21 46 46 25 79 34 7a 58 24 32 36 39 47 43 78 49 77 63 48 53 6d 54 6b 4c 28 44 6c 21 4a 2a 65 73 3e 62 4c 6f 4c 32 57 41 4a 3f 4c } //1 KGvNsd(v&CkE!FF%y4zX$269GCxIwcHSmTkL(Dl!J*es>bLoL2WAJ?L
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}