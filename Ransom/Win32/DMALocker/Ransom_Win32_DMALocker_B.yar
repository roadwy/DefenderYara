
rule Ransom_Win32_DMALocker_B{
	meta:
		description = "Ransom:Win32/DMALocker.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 00 2b 00 5d 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 73 00 75 00 63 00 63 00 65 00 65 00 64 00 65 00 64 00 2c 00 20 00 73 00 61 00 76 00 69 00 6e 00 67 00 3a 00 20 00 25 00 73 00 } //2 [+] Decrypting succeeded, saving: %s
		$a_01_1 = {33 00 2e 00 20 00 49 00 66 00 20 00 79 00 6f 00 75 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 68 00 61 00 76 00 65 00 20 00 42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 73 00 2c 00 20 00 70 00 61 00 79 00 20 00 75 00 73 00 } //2 3. If you already have Bitcoins, pay us
		$a_01_2 = {5c 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 2e 00 74 00 78 00 74 00 } //2 \decrypting.txt
		$a_01_3 = {5c 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //2 \cryptinfo.txt
		$a_01_4 = {42 00 41 00 43 00 4b 00 47 00 52 00 4f 00 55 00 4e 00 44 00 00 00 } //1
		$a_01_5 = {44 4d 41 20 4c 6f 63 6b 65 72 } //2 DMA Locker
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=7
 
}
rule Ransom_Win32_DMALocker_B_2{
	meta:
		description = "Ransom:Win32/DMALocker.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 14 00 00 "
		
	strings :
		$a_00_0 = {44 4d 41 20 4c 6f 63 6b 65 72 20 34 2e 30 } //1 DMA Locker 4.0
		$a_00_1 = {44 4d 41 4c 4f 43 4b 2e 45 4e 43 44 45 43 44 44 } //1 DMALOCK.ENCDECDD
		$a_00_2 = {21 44 4d 41 4c 4f 43 4b 34 2e 30 } //1 !DMALOCK4.0
		$a_00_3 = {00 64 6d 61 5f 69 64 00 } //1 搀慭楟d
		$a_00_4 = {00 64 6d 61 5f 70 75 62 6c 69 63 5f 6b 65 79 00 } //1 搀慭灟扵楬彣敫y
		$a_00_5 = {45 78 65 63 75 74 69 6e 67 20 66 69 73 74 20 6b 6e 6f 63 6b } //1 Executing fist knock
		$a_00_6 = {2f 63 72 79 70 74 6f 2f 67 61 74 65 3f 61 63 74 69 6f 6e 3d } //1 /crypto/gate?action=
		$a_00_7 = {26 62 6f 74 49 64 3d 25 73 } //1 &botId=%s
		$a_00_8 = {26 74 72 61 6e 73 61 63 74 69 6f 6e 49 64 3d 25 73 } //1 &transactionId=%s
		$a_00_9 = {2f 2f 25 73 2f 63 72 79 70 74 6f 2f 63 6c 69 65 6e 74 5f 70 61 79 6d 65 6e 74 5f 69 6e 73 74 72 75 63 74 69 6f 6e 73 3f 62 6f 74 49 64 3d 25 73 } //2 //%s/crypto/client_payment_instructions?botId=%s
		$a_00_10 = {2f 2f 25 73 2f 63 72 79 70 74 6f 2f 63 6c 69 65 6e 74 5f 66 72 65 65 5f 64 65 63 72 79 70 74 3f 62 6f 74 49 64 3d 25 73 } //2 //%s/crypto/client_free_decrypt?botId=%s
		$a_00_11 = {72 61 6e 73 6f 6d 5f 61 6d 6f 75 6e 74 5f 69 6e 63 72 65 61 73 65 5f 61 6d 6f 75 6e 74 } //1 ransom_amount_increase_amount
		$a_00_12 = {72 61 6e 73 6f 6d 5f 61 6d 6f 75 6e 74 5f 69 6e 63 72 65 61 73 65 5f 74 69 6d 65 73 74 61 6d 70 } //1 ransom_amount_increase_timestamp
		$a_00_13 = {5c 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //1 \vssadmin.exe delete shadows
		$a_80_14 = {40 7a 65 72 6f 62 69 74 2e 65 6d 61 69 6c } //@zerobit.email  1
		$a_80_15 = {44 4d 41 4c 4f 43 4b 20 33 36 3a 35 34 3a 31 31 3a 30 35 3a 30 39 3a 31 34 3a 37 36 3a 32 32 } //DMALOCK 36:54:11:05:09:14:76:22  2
		$a_80_16 = {5c 63 72 79 70 74 69 6e 66 6f 2e 74 78 74 } //\cryptinfo.txt  1
		$a_80_17 = {5c 73 76 63 68 6f 73 64 2e 65 78 65 } //\svchosd.exe  1
		$a_80_18 = {5c 64 65 63 72 79 70 74 69 6e 67 2e 74 78 74 } //\decrypting.txt  1
		$a_80_19 = {5c 73 65 6c 65 63 74 2e 62 61 74 } //\select.bat  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*2+(#a_00_10  & 1)*2+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*2+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1) >=8
 
}