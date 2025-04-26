
rule Worm_Win32_Woriply_A{
	meta:
		description = "Worm:Win32/Woriply.A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 4b 65 79 3d 31 46 47 4e 2d 39 44 4e 4e 2d 32 48 4c 5a 2d 4c 39 4d 4b 2d 52 38 44 48 2d 49 38 34 4a } //10 regKey=1FGN-9DNN-2HLZ-L9MK-R8DH-I84J
		$a_01_1 = {6d 61 69 6e 63 6c 61 73 73 3d 6d 75 6c 74 69 70 6c 79 0a } //1
		$a_01_2 = {6d 61 69 6e 63 6c 61 73 73 3d 78 73 65 65 64 6d 61 69 6e 0a } //1 慭湩汣獡㵳獸敥浤楡੮
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}