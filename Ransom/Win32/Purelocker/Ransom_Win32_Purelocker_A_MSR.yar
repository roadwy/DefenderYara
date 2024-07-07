
rule Ransom_Win32_Purelocker_A_MSR{
	meta:
		description = "Ransom:Win32/Purelocker.A!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 6f 70 70 2e 64 6c 6c 00 44 65 6c 65 74 65 4d 75 73 69 63 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 46 69 6e 64 4d 75 73 69 63 00 4d 6f 76 65 4d 75 73 69 63 } //1 牣灹潴灰搮汬䐀汥瑥䵥獵捩䐀汬敒楧瑳牥敓癲牥䘀湩䵤獵捩䴀癯䵥獵捩
	condition:
		((#a_01_0  & 1)*1) >=1
 
}